
rule k3e9_13ac569bcb4ce115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13ac569bcb4ce115"
     cluster="k3e9.13ac569bcb4ce115"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="peed qukart backdoor"
     md5_hashes="['01503848f1de1d6d4d4a1d5636ba94d6','01dd6468b52edab18c945e0c9d72ebe7','d6b0a1aae0bf7981e635f1b013d50e87']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
