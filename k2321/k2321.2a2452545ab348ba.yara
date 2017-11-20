
rule k2321_2a2452545ab348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a2452545ab348ba"
     cluster="k2321.2a2452545ab348ba"
     cluster_size="28"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy flmp"
     md5_hashes="['02d0c17ca800b03c60454c92f7beee79','1400b6ef5d89d4b9c7c2eccc92b6beae','a9f716ef72b2ffbf37ef1f020edf647c']"

   strings:
      $hex_string = { 0d25a8a4c92c412bf84ad6f579e5ab5ee39c837b779c96c005506a8dbf582b3cacf11769a284fa5d643457ccb4ec6e9a369899017846a1954c9f70cdcfafe487 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
