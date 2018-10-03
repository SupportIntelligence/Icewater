
rule k2328_4a167b49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2328.4a167b49c0000b12"
     cluster="k2328.4a167b49c0000b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html script iframe"
     md5_hashes="['8f9a192d90dc32814aad39de02d907005d249b16','b8573cbf834a124b3b9e05418161f5c7be747ce3','d5b402aebe10ed549ddb500369c198b32d836167']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2328.4a167b49c0000b12"

   strings:
      $hex_string = { 233846394541343b0d0a7d0d0a2e62675f62616e6e65725f736c696365207b0d0a096261636b67726f756e642d696d6167653a2075726c28687474703a2f2f77 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
