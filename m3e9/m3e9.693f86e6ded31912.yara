
rule m3e9_693f86e6ded31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f86e6ded31912"
     cluster="m3e9.693f86e6ded31912"
     cluster_size="938"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['027005f10beb3f6b915c8e318b9396bd','027ac24ff143700c716b6096108a7425','111ebb8add47c813b8aef46275b21bd3']"

   strings:
      $hex_string = { 83a79f628ff728af22123183bb64008078efce00a9aac915094c5eac4251a081cbd4e98b44d057938a5dac10eea72f5125198bc991d01f6a2098a931d0bf0846 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
