
rule k3e9_1914e448c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1914e448c4000b16"
     cluster="k3e9.1914e448c4000b16"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['080dbfb0d3157d6a3abba63c28de6be9','1dd5b702162144cd123a9cf1afe0fb79','c51585f3c67c34820bf08a9922e3931a']"

   strings:
      $hex_string = { 067b1657452edf2c2a6d9a95e9bee774d46f02581f83d5fdf0f2a3c127ba798717474eb29ff5cadef5770ad978eacc46dbbc3193946b827f2b9de3325980edf3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
