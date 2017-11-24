
rule n2321_29b081b8d9e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.29b081b8d9e30912"
     cluster="n2321.29b081b8d9e30912"
     cluster_size="42"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['04c0a58c28719ccae08b985e793cf5cd','05fc743566a0b1ad36af5def91bc9b7d','3f97c188733f5d8e1e3a432ae4a15c95']"

   strings:
      $hex_string = { 5de2389fb3874c0050c05a3140c76834db650d587dced3c4dc4fc9828becf9120ac33d723c7115c806097c052cca9539ae4d77333ae5e6b6bbed6a47997aa848 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
