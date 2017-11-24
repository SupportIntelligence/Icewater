
rule n3e9_339a68869caf4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.339a68869caf4912"
     cluster="n3e9.339a68869caf4912"
     cluster_size="25"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector gate aovhryb"
     md5_hashes="['097a6ffc3e8f0a656d5d0990989b46ee','0da31f115eb27d93201059be4d60c400','ae01d2ce2ab00c33ed811e0d817a12b1']"

   strings:
      $hex_string = { ee18f18372e0493953a702b6ceb2c32ba0330c10e97170ec3da1edcc068457b411aed20ecd8a8cb0acbf5941cfca52ded920a317c5bc6b94ef66c16df96e56d6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
