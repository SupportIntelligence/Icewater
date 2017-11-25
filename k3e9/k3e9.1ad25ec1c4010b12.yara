
rule k3e9_1ad25ec1c4010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1ad25ec1c4010b12"
     cluster="k3e9.1ad25ec1c4010b12"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce email"
     md5_hashes="['59c492dad4794a4c0b38f394540fc957','6952b9c89a18905836981201845eeb45','8a745e6def8c543b31a10270e9f63744']"

   strings:
      $hex_string = { 58663d60e80f8486000000814b24000000e06a026a00ff7508ff563c83f8ff74705005fc1900002b43148943108b53083bc272168943088b4f384903c103d1f7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
