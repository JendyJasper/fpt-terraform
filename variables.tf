variable "region" {
    default = "us-east-1"
}

variable "vpc_cidr" {
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

variable "rds_username" {
    default = "fptdb"
    sensitive = true
}

variable "avail_zone" {
    default = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "updated_avail_zone" {
    default = {
        "zone_1": "us-east-1a",
        "zone_2": "us-east-1b",
        "zone_3": "us-east-1c"
    }
}

variable "priv_subnet" {
    default = ["172.168.0.0/20", "172.168.16.0/20", "172.168.32.0/20"]
}


variable "pub_subnet" {
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