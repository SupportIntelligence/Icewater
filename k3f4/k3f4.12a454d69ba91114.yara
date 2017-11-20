
rule k3f4_12a454d69ba91114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.12a454d69ba91114"
     cluster="k3f4.12a454d69ba91114"
     cluster_size="260"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="krypt bladabindi bkdr"
     md5_hashes="['002c8aaa767bb05672c89be60e3d461d','00779365a2377994465dee0639f3deb8','0fee7203cc811ff0572d35596d68ed0b']"

   strings:
      $hex_string = { 03e1120d0809018705f60619015d132f0819016213370811036d133e088100d00f850191007613140711037f134408190186044a08310295135608e900a513b7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
