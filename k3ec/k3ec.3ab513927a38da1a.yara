
rule k3ec_3ab513927a38da1a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.3ab513927a38da1a"
     cluster="k3ec.3ab513927a38da1a"
     cluster_size="423"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="antavmu fileinfector acaohle"
     md5_hashes="['003b12ee32809f1b5ca91525f6f3c8d1','008f645e16ef4909bca9b51d1e406978','062baa84a2a0266315f3679183d7c104']"

   strings:
      $hex_string = { ff520fbe4f1651e8810f000083c40c3bf07410f6471302750a66834f121083c8ffeb0433c08ac35f5e5b595dc3558bec53568b750c8b5d0885db7505bb72e940 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
