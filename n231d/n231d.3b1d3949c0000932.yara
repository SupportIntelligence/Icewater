
rule n231d_3b1d3949c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.3b1d3949c0000932"
     cluster="n231d.3b1d3949c0000932"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp riskware androidos"
     md5_hashes="['10090a0eb255c146044c18c5dd1f8cb1a6d2b592','ba5d2bd07f782703d68b80e2e370abff5a19b07a','06f77b91dcdbabd86a3179d5c0fb1c6e8eec4e27']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.3b1d3949c0000932"

   strings:
      $hex_string = { 7d041ad1a3487533bbe7bdc8cd0129d73e1d00729a28071039738514c409387fae8bba6bb83a7a578e4240e1cf081be490eb6615596e2f377045fd76deca9697 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
