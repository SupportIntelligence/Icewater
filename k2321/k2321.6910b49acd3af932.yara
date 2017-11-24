
rule k2321_6910b49acd3af932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.6910b49acd3af932"
     cluster="k2321.6910b49acd3af932"
     cluster_size="12"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar virtob shyape"
     md5_hashes="['08e568b2f8ce415f6854f6b86c32de4e','325a347777c0c4879da6e2b352c1bde1','eb1fd8cf9e2834146013cd94952f86e9']"

   strings:
      $hex_string = { 7a52e10714cf982a27188f9b871ae64935e443c53de8f296864c454f938cd392e31fd05c5efcc0579cc751835630bbb65a6028349e81610872e96982a14250e0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
