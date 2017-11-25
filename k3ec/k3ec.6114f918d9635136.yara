
rule k3ec_6114f918d9635136
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.6114f918d9635136"
     cluster="k3ec.6114f918d9635136"
     cluster_size="10"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="resur senna malicious"
     md5_hashes="['500fde49bbac4f36aac1aafae7d84093','58bace8d8a508e63076b69bb4f4527ff','ee3fcfed58aca0ba71690f18d8e29acf']"

   strings:
      $hex_string = { 56fc8955f88b55f4f6c201895d0c757ec1fa044a83fa3f76036a3f5a8b4b043b4b08754c83fa20731ebb000000808bcad3eb8d4c0204f7d3215cb844fe097528 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
