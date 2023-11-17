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
    default = "ami-0fc5d935ebf8bc3bc"
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

variable "priv-subnet" {
    default = ["172.168.0.0/20", "172.168.16.0/20", "172.168.32.0/20"]
}

variable "pub-subnet" {
    default = ["172.168.48.0/20", "172.168.64.0/20", "172.168.80.0/20"]
}