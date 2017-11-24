
rule j3ec_6b54834a969b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.6b54834a969b0b12"
     cluster="j3ec.6b54834a969b0b12"
     cluster_size="502"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector aytohpmi malicious"
     md5_hashes="['00447e9f520e6ec4c766c1516dd3cb63','013b3e9eb2f1c5c60a95193e7f5cfe24','0cb3692ceb363b45c1b8daf16044b1fd']"

   strings:
      $hex_string = { edeb797c8ffa4252a1626fab0c314f24233486fe6ed47b51f510fde762b14a4d6c086aee142dc2a54c2b5c6b11cb06e40cc41947919fa823ef7392e3db7e3925 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
