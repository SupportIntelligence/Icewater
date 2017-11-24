
rule k3e9_431ace0e92bb9b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.431ace0e92bb9b12"
     cluster="k3e9.431ace0e92bb9b12"
     cluster_size="105"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rimod emailworm fakefolder"
     md5_hashes="['00191c5d13f66649b9a92927b7d65828','01273d4aec5c39cb4269d4c544b86fda','2f8eab585deb803acc097fc902f23abd']"

   strings:
      $hex_string = { 9ac6001896c0001b9cc70018799c00197a9d0021a2ce0025a2cf002899bf006bd7ff0042b3e20042b2de0052bee7006fd5fd0042baef000c72a5005ac7ff0084 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
