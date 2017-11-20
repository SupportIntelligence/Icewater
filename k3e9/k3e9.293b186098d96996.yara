
rule k3e9_293b186098d96996
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.293b186098d96996"
     cluster="k3e9.293b186098d96996"
     cluster_size="52"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore heuristic malicious"
     md5_hashes="['01b971eea4fae810714ca76f7a4f1c67','027cc4c0ba4993d146c199fd3543a1e0','460a189bff0de0c4cd57d97bc695e7b1']"

   strings:
      $hex_string = { 15931601f039c851002b8cd3d89f8e678868c4ffcb5ca3593dba4ca688293ee5280420cce452fc7e3b56a766e29a7bf4ddd5c59126469510c98186a972783196 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
