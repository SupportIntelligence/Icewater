
rule o3e7_0b315ed2ae211b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.0b315ed2ae211b32"
     cluster="o3e7.0b315ed2ae211b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr dlboost malicious"
     md5_hashes="['05d8866b82f5a6a346630ada0b94df0b','3467f99a51e7eb69a4f2a3e7166930ea','874755fc81a59339694623d1fdafdd61']"

   strings:
      $hex_string = { dc6164185307bb96ab0fd6e8b4819e19eb724eaeaa9c16f9c2a2dd27ed3d46a926a1a757518928fc21c3c59a36e12ac6da9b339085f354a48ad32988e2fd5d59 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
