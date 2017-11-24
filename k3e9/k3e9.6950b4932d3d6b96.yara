
rule k3e9_6950b4932d3d6b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6950b4932d3d6b96"
     cluster="k3e9.6950b4932d3d6b96"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar shyape virtob"
     md5_hashes="['11a3946c808eca59667126d37cb375c7','1673b109d5d7ca7917b523bebf977884','9a99b89bb0f5dd280ab2f40d550f7c4d']"

   strings:
      $hex_string = { 7a52e10714cf982a27188f9b871ae64935e443c53de8f296864c454f938cd392e31fd05c5efcc0579cc751835630bbb65a6028349e81610872e96982a14250e0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
