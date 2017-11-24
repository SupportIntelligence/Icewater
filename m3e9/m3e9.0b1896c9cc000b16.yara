
rule m3e9_0b1896c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b1896c9cc000b16"
     cluster="m3e9.0b1896c9cc000b16"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['049be7868d5e799be01d89851577aac4','277f218b9075c0c117a9e571d6daa867','c88fb071a3e13e50120916031ed3aa5e']"

   strings:
      $hex_string = { 987ef6dea39eff00930e5540b5d2ad1b3ef585e31ea8ab4dd6f2d92f1c375370eaf804188ebb323823552af9974974a6169c1088e5cc8a92e863c04f87a49966 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
