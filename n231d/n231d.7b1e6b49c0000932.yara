
rule n231d_7b1e6b49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.7b1e6b49c0000932"
     cluster="n231d.7b1e6b49c0000932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp androidos riskware"
     md5_hashes="['9e9013d032169475e7c295b41e2fe4d540372bc9','f0ae830c38ba8f952d383d294afa1b149039bbbb','17e618a13ff41b0253da517fdb986ae8b13035d3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.7b1e6b49c0000932"

   strings:
      $hex_string = { 7d041ad1a3487533bbe7bdc8cd0129d73e1d00729a28071039738514c409387fae8bba6bb83a7a578e4240e1cf081be490eb6615596e2f377045fd76deca9697 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
