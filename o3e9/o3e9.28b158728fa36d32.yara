
rule o3e9_28b158728fa36d32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.28b158728fa36d32"
     cluster="o3e9.28b158728fa36d32"
     cluster_size="235"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['02ec4d7624f22734e038e87e3428e888','037b11f01f4f534ee99c1c939bc7e5ae','1bda36e3684f000fd5eb3592b9354b7c']"

   strings:
      $hex_string = { f85618d0bc13bc0c2da3bce6129a07f1ec0639105bff68d2c27c7f1294aa3a5517b25c53096808f7d739024c16af738ef4a69384e47c56393b393093f37b578d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
