
rule n3e9_0000003901106a08
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0000003901106a08"
     cluster="n3e9.0000003901106a08"
     cluster_size="21"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious mypcbackup nsis"
     md5_hashes="['124c7a58c1f36c4f1ca0959cda6f3915','128ee5f97b414e9df55258cd05afcc69','c35f2185e9ec3bbc62893c42e363c71f']"

   strings:
      $hex_string = { 3dccf10ba8e81375688997a7a0d9aa9373015d144269dc19773a500a9af6d02aca539df5955ca2d6c987e7d3275478ba20fe25d23bd1398e491d40cbfad8dec6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
