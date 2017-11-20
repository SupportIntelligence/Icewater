
rule k3e9_1b1b191ad99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1b191ad99b0912"
     cluster="k3e9.1b1b191ad99b0912"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt injector symmi"
     md5_hashes="['0da50f263e73e0f8b37bdd05b56cef68','22f257b7339ff0e91721563acbf88341','ce446553dacb09d9acaa630346f3c513']"

   strings:
      $hex_string = { 3502fc86eb0fa3657b2bf1394e08a9665683d4b4e6b983170c6c726db3bcb63fd095376efeceb05bcf457fc196a11b52b21ccdf37d1ef863dd26135d42bd87e3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
