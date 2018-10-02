
rule m3f8_6916ea48c0000b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.6916ea48c0000b10"
     cluster="m3f8.6916ea48c0000b10"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeinst androidos smsagent"
     md5_hashes="['d36d2392cc6b1c25c45c007814bf77ab1bdd1882','a57335b5e7823ffcb2c02469d096903a2dbc834c','181ed8818c6120d9ee82c987aa32710618213a30']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.6916ea48c0000b10"

   strings:
      $hex_string = { 77436e31757630353942734c4745333352616a4d4e764f2f6f327a6a4151744b5046414964335458775342476b56445a6d37784d707869724f3538486b6d6e68 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
