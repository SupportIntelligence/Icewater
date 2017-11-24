
rule k3e9_4d1e3a9cc6eb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4d1e3a9cc6eb0b32"
     cluster="k3e9.4d1e3a9cc6eb0b32"
     cluster_size="22"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart networkworm"
     md5_hashes="['099065cc52567cb84b8356fc5ff015ed','17ff5d88219aefef715bf9636be5903d','dba9c5ca15820612464dbd7934e2cbdc']"

   strings:
      $hex_string = { 14403bc2894424107cb05f5e5db8010000005b81c40c010000c38d741c1883c9ff8bfe33c0f2aef7d1498d7c2b01880c2b0fbec98bd1c1e902f3a58bca83e103 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
