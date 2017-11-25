
rule o3e9_5992bec9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5992bec9c4000932"
     cluster="o3e9.5992bec9c4000932"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock tdss nabucur"
     md5_hashes="['0fd4b90b122b109e97ba5cd0f720f9e0','468689ee239888da9825bdc71f435aaf','e155319a9001dc968c209ea35a16f386']"

   strings:
      $hex_string = { 005b8fef00577cdd002d59de00406eca0070aded0072a7ea006094d7002664c9005a89d1006595d000202e43004b85ba0085818b00cc700d00d6710300d37308 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
