
rule k2321_19156a48c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.19156a48c4000b16"
     cluster="k2321.19156a48c4000b16"
     cluster_size="12"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['24de47bb10d0aeaebc4e3780c5927caa','263d21e9d294e2e85db8a24c03f31af9','e90a56dff4b6b3d9036ef800d2390adb']"

   strings:
      $hex_string = { 067b1657452edf2c2a6d9a95e9bee774d46f02581f83d5fdf0f2a3c127ba798717474eb29ff5cadef5770ad978eacc46dbbc3193946b827f2b9de3325980edf3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
