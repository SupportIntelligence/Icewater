
rule m2726_4cd2b0941302c4f6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2726.4cd2b0941302c4f6"
     cluster="m2726.4cd2b0941302c4f6"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious stantinko"
     md5_hashes="['beba18cf12f4907357d8e9add1910e5de215d996','aedcd1dfc08c2b884c788984d4ea59540c48198c','67e691e407abc815cd9a60c3266c62fb8b9c9220']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2726.4cd2b0941302c4f6"

   strings:
      $hex_string = { 00294508493bce7fb0894df88bc1250300008079054883c8fc407533b81f85eb51f7e9c1fa058bc2c1e81f03c26bc0648bd12bd075128d816c07000099b99001 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
