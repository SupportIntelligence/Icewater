
rule o3e9_09b042ccea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.09b042ccea210912"
     cluster="o3e9.09b042ccea210912"
     cluster_size="21"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr dlboost zusy"
     md5_hashes="['0ad180ec1f34ad4feb274a4c3a578ae8','1721b6f5fd8dfe21651ecf9de3f35acf','968dfe6503566d11c6463c881871877e']"

   strings:
      $hex_string = { 09145d7e0bda854fcc4b10696c99e25efc9da418892295a68797f27620ee77a750dd3e11333b6ba0ae7fa14cafe18f19c2ed4e00f6cb36a8ca355c16f0dc6196 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
