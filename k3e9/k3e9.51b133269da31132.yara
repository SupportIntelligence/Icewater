
rule k3e9_51b133269da31132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b133269da31132"
     cluster="k3e9.51b133269da31132"
     cluster_size="159"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['050eb33e10a299e948d5a1fd1c4d5d92','0ef21e9aaf83b9e37a364d5bda04e7ee','7f52710ea476377d52d2faa88cd73e31']"

   strings:
      $hex_string = { 000178130001641300014c130001341300011c13000104130001ec120001cc120001b41200018c12000170120001501200012812000108120001bf44ffff40bb }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
