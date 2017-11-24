
rule k3ec_11f14cb8c2a00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.11f14cb8c2a00b12"
     cluster="k3ec.11f14cb8c2a00b12"
     cluster_size="7"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ursu cometer paph"
     md5_hashes="['070f0ed4aa433c4d62cd8d3e8ff1d8c4','556be470ea040456c988049686aabdb6','ec5d8fce39b444a05aafab92c89cfced']"

   strings:
      $hex_string = { 7a655f636f737400071401a509000015697838365f74756e655f696e64696365730004f8000000076b015a140000115838365f54554e455f5343484544554c45 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
