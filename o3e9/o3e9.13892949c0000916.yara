
rule o3e9_13892949c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.13892949c0000916"
     cluster="o3e9.13892949c0000916"
     cluster_size="1104"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor ocna riskware"
     md5_hashes="['00f13cdec352b265282a8ddd5b9fd12f','0125cc66658501703ecea95a6e389c39','0657107786c1189087d6e748fce1e7da']"

   strings:
      $hex_string = { 6ba903afe463b6fad52327f460179ec8994638205f6ed32f753ee68ca7f3ce1d395e8db6dded5ab5fce5d92bbda4c30c9918efa3cc3b1f7a525674ea54ffc795 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
