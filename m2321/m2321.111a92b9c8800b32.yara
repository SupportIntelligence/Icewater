
rule m2321_111a92b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.111a92b9c8800b32"
     cluster="m2321.111a92b9c8800b32"
     cluster_size="76"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['048d9d8a46f6a320dc7c2056062eb6fa','04bc55344cf51e7e9f10472d2a403923','331d1528bba93732b3b8ea76d1a5b66a']"

   strings:
      $hex_string = { 6ad5a6fc3a0c1c72d2cf91354f9ccb093cd03015b2d6f618881b8db45b5237b0ceb8b7013b669a57b4f5164917e0ef10f1988c38f96b7084d4c13f5df459e92d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
