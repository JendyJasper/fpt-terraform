provider "aws" {
    region = var.region
}


provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}



#VPC Creation
module "vpc" {
    source = "terraform-aws-modules/vpc/aws"
    version = "5.5.2"

    name = format("%s_VPC", var.name)
    azs = var.avail_zone
    cidr = var.vpc_cidr
    public_subnets = var.pub_subnet
    private_subnets = var.priv_subnet
    create_igw = true
    single_nat_gateway = true
    enable_nat_gateway = true
    one_nat_gateway_per_az = false
    public_subnet_tags = {
      "kubernetes.io/cluster/fpt-cluster" = "shared"
      "kubernetes.io/role/elb" = "1"
    }
    private_subnet_tags = {
      "kubernetes.io/cluster/fpt-cluster" = "shared"
      "kubernetes.io/role/internal-elb" = "1"
    }
    nat_eip_tags = {
        Name = format("%s_eip", var.name)
    }
    private_route_table_tags = {
        Name = format("%s_private_rtb", var.name)
        }
    public_route_table_tags = {
        Name = format("%s_public_rtb", var.name)
        }
    igw_tags = {
        Name = format("%s_igw", var.name)
        }
    nat_gateway_tags = {
        Name = format("%s_nat_gateway", var.name)
    }
}


#Bastion Security group
# module "bastion-security-group" {
#   source  = "terraform-aws-modules/security-group/aws"
#   version = "5.1.0"

#   name = "bastion-security-group"
#   description = "The security group which enables ssh access to the bastion server from the workstation IP address"
#   vpc_id = module.vpc.vpc_id
#   ingress_cidr_blocks = ["125.235.133.125/32"]
#   ingress_rules = ["ssh-tcp"]
#   tags = {
#     Name = format("%s-bastion-sg", var.name)
#   }
#   egress_cidr_blocks = [ "0.0.0.0/0" ]
#   egress_rules = [ "all-all" ]
  
# }


#App security group
# module "app-security-group" {
#   source  = "terraform-aws-modules/security-group/aws"
#   version = "5.1.0"
  
#   name = "app-security-group"
#   description = "Security group that handles traffic for the app server"
#   vpc_id = module.vpc.vpc_id
#   ingress_cidr_blocks = ["0.0.0.0/0"]
#   ingress_rules = ["http-80-tcp", "https-443-tcp"]

#   computed_ingress_with_source_security_group_id = [
#     {
#         rule = "ssh-tcp"
#         source_security_group_id = module.bastion-security-group.security_group_id
#     }
#   ]
#   egress_cidr_blocks = [ "0.0.0.0/0" ]
#   egress_rules = [ "all-all" ]
#   tags = {
#     Name = format("%s-app-sg", var.name)
#   }
# }


#RDS security group
# module "rds-security-group" {
#   source  = "terraform-aws-modules/security-group/aws"
#   version = "5.1.0"

#   name = "rds-security-group"
#   description = "Security group that handles traffic for the rds server"
#   vpc_id = module.vpc.vpc_id

#   computed_ingress_with_source_security_group_id = [
#     {
#         rule = "postgresql-tcp"
#         source_security_group_id = module.bastion-security-group.security_group_id
#     },
    
#     {
#         rule = "postgresql-tcp"
#         source_security_group_id = module.app-security-group.security_group_id
#     },
#     {
#         rule = "http-80-tcp"
#         source_security_group_id = module.app-security-group.security_group_id
#     },
#     {
#         rule = "https-443-tcp"
#         source_security_group_id = module.app-security-group.security_group_id
#     }
#   ]
#   egress_cidr_blocks = [ "0.0.0.0/0" ]
#   egress_rules = [ "all-all" ]
#   number_of_computed_ingress_with_source_security_group_id = 4


#   tags = {
#     Name = format("%s-rds-sg", var.name)
#   } 
# }


#Prometheus security group
# module "prometheus-security-group" {
#   source  = "terraform-aws-modules/security-group/aws"
#   version = "5.1.0"
  
#   vpc_id = module.vpc.vpc_id
#   name = "prometheus-security-group"
#   description = "Security group that handles traffic for the prometheus server"
#   ingress_cidr_blocks = ["0.0.0.0/0"]
#   ingress_rules = ["http-80-tcp", "https-443-tcp", "prometheus-http-tcp", "prometheus-node-exporter-http-tcp", "grafana-tcp", "loki-grafana" ]
#   computed_ingress_with_source_security_group_id = [
#     {
#         rule = "ssh-tcp"
#         source_security_group_id = module.bastion-security-group.security_group_id
#     }
#   ]
#   egress_cidr_blocks = [ "0.0.0.0/0" ]
#   egress_rules = [ "all-all" ]
#   number_of_computed_ingress_with_source_security_group_id = 1
#   tags = {
#     Name = format("%s-prometheus-sg", var.name)
#   }

# }


#ELK security group
# module "elk-security-group" {
#   source  = "terraform-aws-modules/security-group/aws"
#   version = "5.1.0"

#   vpc_id = module.vpc.vpc_id
#   name = "ELK-security-group"
#   description = "Security group that handles traffic for the ELK server"
#   ingress_cidr_blocks = ["0.0.0.0/0"]
#   ingress_rules = ["http-80-tcp", "https-443-tcp", "logstash-tcp" , "kibana-tcp", "elasticsearch-rest-tcp", "elasticsearch-java-tcp" ]


#   computed_ingress_with_source_security_group_id = [
#     {
#         rule = "ssh-tcp"
#         source_security_group_id = module.bastion-security-group.security_group_id
#     }
#   ]
#   egress_cidr_blocks = [ "0.0.0.0/0" ]
#   egress_rules = [ "all-all" ]
#   number_of_computed_ingress_with_source_security_group_id = 1
#   tags = {
#     Name = format("%s-elk-sg", var.name)
#   }
# }


#Create private key to enable ssh access to the servers
module "key_pair" {
  source  = "terraform-aws-modules/key-pair/aws"
  version = "2.0.2"

  key_name           = "FPT_Private_Key"
  create_private_key = true
}

#save private key to a file
resource "local_file" "private_key_file" {
  filename = var.private_key_path
  content  = module.key_pair.private_key_pem
}

#save public key to a file
resource "local_file" "public_key_file" {
  filename = var.public_key_path
  content  = module.key_pair.public_key_openssh
}


#create bastion ec2-instance 
# module "bastion_ec2_instance" {
#   source  = "terraform-aws-modules/ec2-instance/aws"
#   version = "5.5.0"

#   name = "bastion-ec2-instance"

#   instance_type          = var.instance_type
#   key_name               = module.key_pair.key_pair_name
#   monitoring             = true
#   vpc_security_group_ids = [module.bastion-security-group.security_group_id]
#   subnet_id              = module.vpc.public_subnets[0]
#   associate_public_ip_address  = true
#   ami = var.ami
#   iam_role_description = "EKS role"
#   iam_role_name = module.eks.cluster_iam_role_name
#   tags = {
#     Name = format("%s-bastion-ec2-instance", var.name)
#   }

# }

# #create elk ec2-instance 
# module "elk-ec2-instance" {
#   source  = "terraform-aws-modules/ec2-instance/aws"
#   version = "5.5.0"

#   name = "elk-ec2-instance"

#   instance_type          = var.instance_type
#   key_name               = module.key-pair.key_pair_name
#   monitoring             = true
#   vpc_security_group_ids = [module.elk-security-group.security_group_id]
#   subnet_id              = module.vpc.public_subnets[1]
#   associate_public_ip_address  = true
#   tags = {
#     Name = format("%s-elk-ec2-instance", var.name)
#   }

# }

#create prometheus ec2-instance 
# module "prometheus-ec2-instance" {
#   source  = "terraform-aws-modules/ec2-instance/aws"
#   version = "5.5.0"

#   name = "elk-ec2-instance"

#   instance_type          = var.instance_type
#   key_name               = module.key-pair.key_pair_name
#   monitoring             = true
#   vpc_security_group_ids = [module.prometheus-security-group.security_group_id]
#   subnet_id              = module.vpc.public_subnets[2]
#   associate_public_ip_address  = true
#   tags = {
#     Name = format("%s-prometheus-ec2-instance", var.name)
#   }

# }

# #create app ec2-instance 
# module "app-ec2-instance" {
#   source  = "terraform-aws-modules/ec2-instance/aws"
#   version = "5.5.0"

#   name = "app-ec2-instance"

#   instance_type          = var.instance_type
#   key_name               = module.key-pair.key_pair_name
#   monitoring             = true
#   vpc_security_group_ids = [module.app-security-group.security_group_id]
#   subnet_id              = module.vpc.private_subnets[0]
#   associate_public_ip_address  = true
#   tags = {
#     Name = format("%s-app-ec2-instance", var.name)
#   }

# }

#create postgres rds
# module "rds" {
#   source  = "terraform-aws-modules/rds/aws"
#   version = "6.3.0"
#   identifier = "fptdb"

#   engine = "postgres"
#   engine_version = "15.3"
#   instance_class = "db.t3.micro"
#   allocated_storage = 20

#   # DB parameter group
#   family = "postgres15"

#   db_name  = "fptdb"
#   username = var.rds-username
#   port     = "5432"
#   manage_master_user_password = true

#   iam_database_authentication_enabled = true
#   db_subnet_group_name = "fpt-subnet-group"
#   vpc_security_group_ids = [module.rds-security-group.security_group_id]

#   maintenance_window = "Mon:00:00-Mon:03:00"
#   backup_window      = "03:00-06:00"

#   create_db_subnet_group = true
#   subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[1], module.vpc.private_subnets[2]]

#   deletion_protection = false
# }

#IAM EFS CSI Driver Role
# module "iam_efs_csi_role_eks" {
#   source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
#   version = "5.33.1"

#   role_name = "AmazonEKS_EFS_CSI_DriverRole"
#   attach_efs_csi_policy = true

#   oidc_providers = {
#     main = {
#       provider_arn               = module.eks.oidc_provider_arn
#       namespace_service_accounts = ["kube-system:efs-csi-controller-sa", "default:efs-csi-controller-sa", "default:prometheus-stack-grafana" ]
#     }
#   }

# }

module "iam_ebs_csi_role_eks" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.33.1"

  role_name = "AmazonEKS_EBS_CSI_DriverRole"
  attach_ebs_csi_policy  = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "default:ebs-csi-controller-sa", "monitoring:ebs-csi-controller-sa", "monitoring:prometheus-stack-grafana" ]
    }
  }

}

#eks private cluster
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.21.0"

  cluster_name    = "fpt-cluster"
  cluster_version = "1.28"
  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true
  cluster_addons_timeouts = {
    create = "30m"
    update = "30m"
    delete = "30m"
  }

  cluster_addons = {
    coredns = {
      configuration_values = jsonencode({
        computeType = "Fargate"
      })  #this resolves coredns degraded error
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-efs-csi-driver = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }

  vpc_id = module.vpc.vpc_id
  subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[1], module.vpc.private_subnets[2]]
  control_plane_subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[1], module.vpc.private_subnets[2]]


  # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    ami_type       = "AL2_x86_64"
    instance_types = ["t3.small"]

    attach_cluster_primary_security_group = true
   
  }

  eks_managed_node_groups = {
    blue = {
      iam_role_additional_policies = {
        AmazonEBSCSIDriverPolicy = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
      }
    }
    green = {
      min_size     = 1
      max_size     = 2
      desired_size = 1

      instance_types = ["t3.small"]
      capacity_type  = "SPOT"

      # create_iam_role  = false
      # iam_role_arn = module.iam_ebs_csi_role_eks.iam_role_arn
      iam_role_additional_policies = {
        AmazonEBSCSIDriverPolicy = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
      }
    }
    }


  # Fargate Profile(s)
  fargate_profiles = {
    fpt-profile = {
      name = "default"
      iam_role_additional_policies = {
        AmazonEFSCSIDriverPolicy = "arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
      }
      selectors = [
        {
          namespace = "kube-system"
          labels = {
            k8s-app = "kube-dns"
          }
        },
        {
          namespace = "default"
        },
        {
          namespace = "main-fpt"
        }
      ]

      tags = {
        Owner = "test"
      }

      timeouts = {
        create = "20m"
        delete = "20m"
      }
    }
  }
  
  # aws-auth configmap
  create_aws_auth_configmap = false
  manage_aws_auth_configmap = true

  aws_auth_roles = [
    {
      rolearn  = "arn:aws:iam::571207880192:role/fpt_eks_role"
      username = "fpt_eks_role"
      groups   = ["system:masters"]
    },
  ]

  aws_auth_users = [
    {
      userarn  = "arn:aws:iam::571207880192:user/fpt_eks_user"
      username = "fpt_eks_user"
      groups   = ["system:masters"]
    },
    {
      userarn  = "arn:aws:iam::571207880192:user/terraform"
      username = "terraform"
      groups   = ["system:masters"]
    },
  ]

  aws_auth_accounts = [
    "571207880192",
  ]

  tags = {
    Name = format("%s_eks", var.name)
    Terraform = "true"
  }

}


#EFS Module
# module "efs" {
#   source  = "terraform-aws-modules/efs/aws"
#   version = "1.4.0"

#   # File system
#   name = format("%s-efs", var.name)
#   creation_token = format("%s-token", var.name)
#   encrypted = true
#   kms_key_arn = module.kms.key_arn

#   performance_mode                = var.performance_mode 
#   throughput_mode                 = var.throughput_mode
#   provisioned_throughput_in_mibps = var.provisioned_throughput_in_mibps
#   lifecycle_policy = {
#     transition_to_ia                    = "AFTER_30_DAYS"
#     transition_to_primary_storage_class = "AFTER_1_ACCESS"
#   }

#    # File system policy
#   attach_policy = false

#     # Mount targets / security group
#   mount_targets = {
#     for k, v in zipmap(var.avail-zone, module.vpc.private_subnets) : k => {
#     subnet_id = v
#   }
#   }

#   security_group_description = format("%s-EFS security group", var.name)
#   security_group_vpc_id      = module.vpc.vpc_id
#   security_group_rules = {
#     vpc = {
#       # relying on the defaults provdied for EFS/NFS (2049/TCP + ingress)
#       description = "NFS ingress from VPC private"
#       cidr_blocks = module.vpc.private_subnets_cidr_blocks
#     }
#     cluster_primary_security_group_id = {
#       # relying on the defaults provdied for EFS/NFS (2049/TCP + ingress)
#       description = "NFS ingress from cluster_primary_security_group_id"
#       source_security_group_id = module.eks.cluster_primary_security_group_id
#     }
#     cluster_security_group_id = {
#       # relying on the defaults provdied for EFS/NFS (2049/TCP + ingress)
#       description = "NFS ingress from cluster_security_group_id"
#       source_security_group_id = module.eks.cluster_security_group_id
#     }
#     node_security_group_id = {
#       # relying on the defaults provdied for EFS/NFS (2049/TCP + ingress)
#       description = "NFS ingress from node_security_group_id"
#       source_security_group_id = module.eks.node_security_group_id
#     }
#   }

#   # Access point(s)
#   access_points = {
#     prometheus = {
#       name = "prometheus"
#       posix_user = {
#         gid            = 1006
#         uid            = 1006
#         secondary_gids = [1002]
#       }
#       root_directory = {
#         path = "/var/lib/kubelet/pods"
#         creation_info = {
#           owner_gid   = 1006
#           owner_uid   = 1006
#           permissions = "777"
#         }
#       }

#       tags = {
#         Additionl = "yes"
#       }
#     }
#     grafana = {
#       name = "grafana"
#       posix_user = {
#         gid            = 1002
#         uid            = 1002
#         secondary_gids = [1003]
#       }
#       root_directory = {
#         path = "/var/lib/kubelet/pods"
#         creation_info = {
#           owner_gid   = 1002
#           owner_uid   = 1002
#           permissions = "777"
#         }
#       }

#       tags = {
#         Additionl = "yes"
#       }
#     }
#     thanosruler = {
#       name = "thanosruler"
#       posix_user = {
#         gid            = 1003
#         uid            = 1003
#         secondary_gids = [1004]
#       }
#       root_directory = {
#         path = "/var/lib/kubelet/pods"
#         creation_info = {
#           owner_gid   = 1003
#           owner_uid   = 1003
#           permissions = "777"
#         }
#       }

#       tags = {
#         Additionl = "yes"
#       }
#     }
#     alertmanager = {
#       name = "alertmanager"
#       posix_user = {
#         gid            = 1004
#         uid            = 1004
#         secondary_gids = [1005]
#       }
#       root_directory = {
#         path = "/var/lib/kubelet/pods"
#         creation_info = {
#           owner_gid   = 1004
#           owner_uid   = 1004
#           permissions = "777"
#         }
#       }

#       tags = {
#         Additionl = "yes"
#       }
#     }
#     root = {
#       root_directory = {
#         path = "/"
#         creation_info = {
#           owner_gid   = 1001
#           owner_uid   = 1001
#           permissions = "777"
#         }
#       }
#     }
#   }

#    # Backup policy
#   enable_backup_policy = true

#   # Replication configuration
#   create_replication_configuration = true
#   replication_configuration_destination = {
#     region = "eu-west-2"
#   }

#   tags = {
#     Name = format("%s-efs", var.name)
# }
# }

module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "2.1.0"

  description = "EFS key usage"
  key_usage   = "ENCRYPT_DECRYPT"
}

