provider "aws" {
    region = var.region
}


#VPC Creation
module "vpc" {
    source = "terraform-aws-modules/vpc/aws"

    name = format("%s-VPC", var.name)
    azs = var.avail-zone
    cidr = var.vpc-cidr
    public_subnets = var.pub-subnet
    private_subnets = var.priv-subnet
    create_igw = true
    single_nat_gateway = true
    enable_nat_gateway = true
    one_nat_gateway_per_az = false
    nat_eip_tags = {
        Name = format("%s-eip", var.name)
    }
    private_route_table_tags = {
        Name = format("%s-private-rtb", var.name)
        }
    public_route_table_tags = {
        Name = format("%s-public-rtb", var.name)
        }
    igw_tags = {
        Name = format("%s-igw", var.name)
        }
    nat_gateway_tags = {
        Name = format("%s-nat_gateway", var.name)
    }
}


#Bastion Security group
module "bastion-security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"

  name = "bastion-security-group"
  description = "The security group which enables ssh access to the bastion server from the workstation IP address"
  vpc_id = module.vpc.vpc_id
  ingress_cidr_blocks = ["125.235.133.125/32"]
  ingress_rules = ["ssh-tcp"]
  tags = {
    Name = format("%s-bastion-sg", var.name)
  }
  egress_cidr_blocks = [ "0.0.0.0/0" ]
  egress_rules = [ "all-all" ]
  
}


#App security group
module "app-security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"
  
  name = "app-security-group"
  description = "Security group that handles traffic for the app server"
  vpc_id = module.vpc.vpc_id
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules = ["http-80-tcp", "https-443-tcp"]

  computed_ingress_with_source_security_group_id = [
    {
        rule = "ssh-tcp"
        source_security_group_id = module.bastion-security-group.security_group_id
    }
  ]
  egress_cidr_blocks = [ "0.0.0.0/0" ]
  egress_rules = [ "all-all" ]
  tags = {
    Name = format("%s-app-sg", var.name)
  }
}


#RDS security group
module "rds-security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"

  name = "rds-security-group"
  description = "Security group that handles traffic for the rds server"
  vpc_id = module.vpc.vpc_id

  computed_ingress_with_source_security_group_id = [
    {
        rule = "postgresql-tcp"
        source_security_group_id = module.bastion-security-group.security_group_id
    },
    
    {
        rule = "postgresql-tcp"
        source_security_group_id = module.app-security-group.security_group_id
    },
    {
        rule = "http-80-tcp"
        source_security_group_id = module.app-security-group.security_group_id
    },
    {
        rule = "https-443-tcp"
        source_security_group_id = module.app-security-group.security_group_id
    }
  ]
  egress_cidr_blocks = [ "0.0.0.0/0" ]
  egress_rules = [ "all-all" ]
  number_of_computed_ingress_with_source_security_group_id = 4


  tags = {
    Name = format("%s-rds-sg", var.name)
  } 
}


#Prometheus security group
module "prometheus-security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"
  
  vpc_id = module.vpc.vpc_id
  name = "prometheus-security-group"
  description = "Security group that handles traffic for the prometheus server"
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules = ["http-80-tcp", "https-443-tcp", "prometheus-http-tcp", "prometheus-node-exporter-http-tcp", "grafana-tcp", "loki-grafana" ]
  computed_ingress_with_source_security_group_id = [
    {
        rule = "ssh-tcp"
        source_security_group_id = module.bastion-security-group.security_group_id
    }
  ]
  egress_cidr_blocks = [ "0.0.0.0/0" ]
  egress_rules = [ "all-all" ]
  number_of_computed_ingress_with_source_security_group_id = 1
  tags = {
    Name = format("%s-prometheus-sg", var.name)
  }

}


#ELK security group
module "elk-security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"

  vpc_id = module.vpc.vpc_id
  name = "ELK-security-group"
  description = "Security group that handles traffic for the ELK server"
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules = ["http-80-tcp", "https-443-tcp", "logstash-tcp" , "kibana-tcp", "elasticsearch-rest-tcp", "elasticsearch-java-tcp" ]


  computed_ingress_with_source_security_group_id = [
    {
        rule = "ssh-tcp"
        source_security_group_id = module.bastion-security-group.security_group_id
    }
  ]
  egress_cidr_blocks = [ "0.0.0.0/0" ]
  egress_rules = [ "all-all" ]
  number_of_computed_ingress_with_source_security_group_id = 1
  tags = {
    Name = format("%s-elk-sg", var.name)
  }
}


#Create private key to enable ssh access to the servers
module "key-pair" {
  source  = "terraform-aws-modules/key-pair/aws"
  version = "2.0.2"

  key_name           = "FPT-Private-Key"
  create_private_key = true
}


#create bastion ec2-instance 
module "bastion-ec2-instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.5.0"

  name = "bastion-ec2-instance"

  instance_type          = var.instance_type
  key_name               = module.key-pair.key_pair_name
  monitoring             = true
  vpc_security_group_ids = [module.bastion-security-group.security_group_id]
  subnet_id              = module.vpc.public_subnets[0]
  associate_public_ip_address  = true
  tags = {
    Name = format("%s-bastion-ec2-instance", var.name)
  }

}

#create elk ec2-instance 
module "elk-ec2-instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.5.0"

  name = "elk-ec2-instance"

  instance_type          = var.instance_type
  key_name               = module.key-pair.key_pair_name
  monitoring             = true
  vpc_security_group_ids = [module.elk-security-group.security_group_id]
  subnet_id              = module.vpc.public_subnets[1]
  associate_public_ip_address  = true
  tags = {
    Name = format("%s-elk-ec2-instance", var.name)
  }

}

#create prometheus ec2-instance 
module "prometheus-ec2-instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.5.0"

  name = "elk-ec2-instance"

  instance_type          = var.instance_type
  key_name               = module.key-pair.key_pair_name
  monitoring             = true
  vpc_security_group_ids = [module.prometheus-security-group.security_group_id]
  subnet_id              = module.vpc.public_subnets[2]
  associate_public_ip_address  = true
  tags = {
    Name = format("%s-prometheus-ec2-instance", var.name)
  }

}

#create app ec2-instance 
module "app-ec2-instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.5.0"

  name = "app-ec2-instance"

  instance_type          = var.instance_type
  key_name               = module.key-pair.key_pair_name
  monitoring             = true
  vpc_security_group_ids = [module.app-security-group.security_group_id]
  subnet_id              = module.vpc.private_subnets[0]
  associate_public_ip_address  = true
  tags = {
    Name = format("%s-app-ec2-instance", var.name)
  }

}

#create postgres rds
module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "6.3.0"
  identifier = "fptdb"

  engine = "postgres"
  engine_version = "15.3"
  instance_class = "db.t3.micro"
  allocated_storage = 20

  # DB parameter group
  family = "postgres15"

  db_name  = "fptdb"
  username = var.rds-username
  port     = "5432"
  manage_master_user_password = true

  iam_database_authentication_enabled = true
  db_subnet_group_name = "fpt-subnet-group"
  vpc_security_group_ids = [module.rds-security-group.security_group_id]

  maintenance_window = "Mon:00:00-Mon:03:00"
  backup_window      = "03:00-06:00"

  create_db_subnet_group = true
  subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[1], module.vpc.private_subnets[2]]

  deletion_protection = false
}