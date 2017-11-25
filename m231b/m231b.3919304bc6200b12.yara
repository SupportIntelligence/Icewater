
rule m231b_3919304bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.3919304bc6200b12"
     cluster="m231b.3919304bc6200b12"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['132ac6a4391f79a18d5da865753aa8fc','176148edf63c574c6e2c1bd63004c856','e72b9e0a1d351e6809d20dd33d47c296']"

   strings:
      $hex_string = { 35393032383136433434334646414139443831463732333439444536433139373539324636434237314135413538303642443045313534323345363736323038 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
