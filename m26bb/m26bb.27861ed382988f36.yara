
rule m26bb_27861ed382988f36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.27861ed382988f36"
     cluster="m26bb.27861ed382988f36"
     cluster_size="817"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadadmin downloadmin malicious"
     md5_hashes="['f5c9b77ef1658fe3313258190c842a424371b205','7a12722c43de7b31e0477390f4e9208209acc01b','3ef5105f921cceb76dd13866c7177c95bf6d459b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.27861ed382988f36"

   strings:
      $hex_string = { bcb297ffbab095feb9ae93feb7ac90ffb5aa8efeb4a88cfeb3a689ffb1a486feafa284feae9f82ffab9d7ffea99a7cfea49679ffa6987dfebeb8abfec6c4bf5b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
