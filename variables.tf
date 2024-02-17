variable "region" {
    default = "us-east-1"
}

variable "vpc-cidr" {
    default = "172.168.0.0/16"
}

variable "name" {
    default = "FPT"
}

variable "ami" {
    default = "ami-052501ccfd3fb7c9f"
}

variable "instance_type" {
    default = "t2.micro"
}

variable "rds-username" {
    default = "fptdb"
    sensitive = true
}

variable "avail-zone" {
    default = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "updated-avail-zone" {
    default = {
        "zone-1": "us-east-1a",
        "zone-2": "us-east-1b",
        "zone-3": "us-east-1c"
    }
}

variable "priv-subnet" {
    default = ["172.168.0.0/20", "172.168.16.0/20", "172.168.32.0/20"]
}


variable "pub-subnet" {
    default = ["172.168.48.0/20", "172.168.64.0/20", "172.168.80.0/20"]
}

variable "performance_mode" {
    default = "maxIO"
}

variable "throughput_mode" {
    default = "provisioned"
}

variable "provisioned_throughput_in_mibps" {
    default = 256
}

# variable "subnets" {
#     default = {
#         "priv-subnet-1": {"az": "us-east-1a", "cidr": "172.168.0.0/20"},
#         "priv-subnet-2": {"az": "us-east-1b", "cidr": "172.168.16.0/20"},
#         "priv-subnet-3": {"az": "us-east-1c", "cidr": "172.168.32.0/20"},
#         "pub-subnet-1": {"az": "us-east-1a", "cidr": "172.168.48.0/20"},
#         "pub-subnet-2": {"az": "us-east-1b", "cidr": "172.168.64.0/20"},
#         "pub-subnet-3": {"az": "us-east-1c", "cidr": "172.168.80.0/20"}
#     }
# }