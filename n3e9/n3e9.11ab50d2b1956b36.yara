
rule n3e9_11ab50d2b1956b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.11ab50d2b1956b36"
     cluster="n3e9.11ab50d2b1956b36"
     cluster_size="12"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut graftor shodi"
     md5_hashes="['08e7208bcc8248209cb7bcef4cea4232','12b52a703db1f7cf6f48d408cf899bbd','fd0523150c9426f3f3343bf7ed8a8bf6']"

   strings:
      $hex_string = { 7f1a3791a23d3a6d68af2313f317a0bdd061b1bc64ff8e39d8bf43b23ffec6f775da3e82ad1ffd116050f4f5efc0537e05c51d77e6228a077321e433b96a4d57 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
