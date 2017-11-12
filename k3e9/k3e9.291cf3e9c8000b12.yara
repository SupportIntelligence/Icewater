
rule k3e9_291cf3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291cf3e9c8000b12"
     cluster="k3e9.291cf3e9c8000b12"
     cluster_size="830"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['003643f8858de88dbae23885201f620b','01105d853483d9bacbd8be0e18780a80','1340e55d9b9c40e4d2438ced42723579']"

   strings:
      $hex_string = { 40008d4900e4674000ec674000f4674000fc674000046840000c68400014684000276840008b448e1c89448f1c8b448e1889448f188b448e1489448f148b448e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
