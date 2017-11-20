
rule m3e9_4a7c4b0caeb0d311
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4a7c4b0caeb0d311"
     cluster="m3e9.4a7c4b0caeb0d311"
     cluster_size="429"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jrau coinminer genome"
     md5_hashes="['00de624426ba35d5a74665fda40bc0fb','01c02c9111a6acb00baab23613f38a71','1b8dd96a4291d3cb2b5c3a2ab0ba25cb']"

   strings:
      $hex_string = { 3bd37c088bc299f7fb004603005604f60578104300015e7414803930750f6a038d41015051e8f41dffff83c40c807dfc0074078b4df8836170fd8bc75f5bc9c3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
