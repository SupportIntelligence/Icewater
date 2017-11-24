
rule k3ed_29afa0c9c0001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.29afa0c9c0001932"
     cluster="k3ed.29afa0c9c0001932"
     cluster_size="86"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="estiwir rkmk onlinegames"
     md5_hashes="['02bca7bd4874a707c3dbb25e142e7fc3','0b43755a1a9146a4732d4b5680db1a6a','486ce183dada4d406e965a6f092fbf4c']"

   strings:
      $hex_string = { 4ff9b239aea15b389b40dfd2b89a57da11e674a45a8583b9cee1d045454545aae36f491fdefd5b4731bbe5d1e48a3af2ab9aff8ff7c2a91c195a3046b53e4a35 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
