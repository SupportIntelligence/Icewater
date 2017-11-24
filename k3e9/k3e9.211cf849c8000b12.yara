
rule k3e9_211cf849c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.211cf849c8000b12"
     cluster="k3e9.211cf849c8000b12"
     cluster_size="1822"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor darkkomet malicious"
     md5_hashes="['004a0c1c10184283fb18d0436e66b8f7','00aada348a663e89afffdf31a3b324da','03d548457eb50206be5cbff622e338fa']"

   strings:
      $hex_string = { 140bd3e03b55f4731e8d7455a48bff0fb73e2bc785c07e0c424183c60203c03b55f472eb8b75dcb8010000008bf8d3e7017de8897dd0394508750d817de8b005 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
