
rule o3e9_15792c629ed3699a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.15792c629ed3699a"
     cluster="o3e9.15792c629ed3699a"
     cluster_size="961"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['003e92a948e836e490410dcbc7e64736','00873707087ccddba540d66c3834b819','039c92e68e3d756c592dd94108fe3c4d']"

   strings:
      $hex_string = { e85a96dca00014a0b9fd4156feedfd7ab550e4121ed9448f2939fd0a7cc465c5708a0e2402772a91ba1059f124fd56cf8f64d56a562c587ed3890603a767ae72 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
