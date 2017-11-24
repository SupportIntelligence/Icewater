
rule j2321_2932997add1b9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.2932997add1b9932"
     cluster="j2321.2932997add1b9932"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bavs upatre cutwail"
     md5_hashes="['3dfdcfa6ef1d99779de6f394c924a8be','6555a15c90d88a96abc0be94a29c2f98','a0b57ba75cef7ea25cfbf56a9ebbed1e']"

   strings:
      $hex_string = { 0ef2761b233f37efd966ac874f80a5cdb33d9ea8a17139f1276aa6dee3890a587b3c61675a8af3099b3c9f451a4b4047b57c8cc811fd3574921c2285f4597d20 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
