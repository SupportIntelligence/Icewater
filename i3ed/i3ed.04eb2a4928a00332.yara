
rule i3ed_04eb2a4928a00332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.04eb2a4928a00332"
     cluster="i3ed.04eb2a4928a00332"
     cluster_size="1507"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris gamarue zusy"
     md5_hashes="['0019e379ff0268c2c979499dc850e8d1','002ea48674cf132f67a497c6a21920a5','030e19149e4cd0a779fbdd8dfacbd27d']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a14032001083ee04ebea50ff151820001083254032001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
