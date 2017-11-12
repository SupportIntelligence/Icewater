
rule k3e9_493e732495a31916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e732495a31916"
     cluster="k3e9.493e732495a31916"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['03080d6d4dfac3d62867f0ae2480c4da','094ddc55d66a5a123a2de178ce7a5718','6dee122b2041284be317c532f0e3937b']"

   strings:
      $hex_string = { a8989000d8d0c80000000000a898900030005800d5ccc800c0c0c00048406000a084b800a8987800f5eacf0242004200d7a52f02a0a0a402ecd59d02ffffff02 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
