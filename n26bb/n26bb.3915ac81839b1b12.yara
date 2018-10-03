
rule n26bb_3915ac81839b1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3915ac81839b1b12"
     cluster="n26bb.3915ac81839b1b12"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="remoteadmin ammyy malicious"
     md5_hashes="['e5dd2d1f7892e86f6b9491e9c85eb9a2130ca114','f7f0faf5b78ebe2595fc7a7820cbc51163795870','cd45730949f063bf2dede705211ed96caded28ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3915ac81839b1b12"

   strings:
      $hex_string = { 10508b45e0ff7004ff15e0e54700b8ec064100c3515356578bf98d4f10894c240ce86c6a0100a164624a006a0333d259f7f133f68bd885db7e2c5533edb95862 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
