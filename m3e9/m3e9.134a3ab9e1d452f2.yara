
rule m3e9_134a3ab9e1d452f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.134a3ab9e1d452f2"
     cluster="m3e9.134a3ab9e1d452f2"
     cluster_size="98"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['03954c0f23e834c65c2b0a18727bef2b','055565039c87834b9619a03fc15967c5','a6827eb5a762a1d2075e1570de0b9a69']"

   strings:
      $hex_string = { 0cf30bd40bec0a040a950829077505c503fe013a0093feeefc9dfb50faa4f9fbf817f933f90ffaeafa43fc98fd25ffac003e02cc032e058d0690078f08e40836 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
