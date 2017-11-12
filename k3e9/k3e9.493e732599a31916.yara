
rule k3e9_493e732599a31916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e732599a31916"
     cluster="k3e9.493e732599a31916"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['088843f33abbf2ddb7c3f08b6617387d','0ca7a8ffb31180f714325910ef0e56ea','dcdfc7329d7e3df5cc2f5dfb66f030b5']"

   strings:
      $hex_string = { a8989000d8d0c80000000000a898900030005800d5ccc800c0c0c00048406000a084b800a8987800f5eacf0242004200d7a52f02a0a0a402ecd59d02ffffff02 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
