
rule m2321_12966a5456aa4aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.12966a5456aa4aba"
     cluster="m2321.12966a5456aa4aba"
     cluster_size="71"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddenapp androidos acbd"
     md5_hashes="['0059841f984d14e1f1caa549286cee0b','03ea563555c74aa9485e36883384ec14','383fdb94aee3e384b46e2a168dd9316d']"

   strings:
      $hex_string = { 30cada59926e71a04d20bea38e762e3595f15ca6b793129cd4a2471d36e1d2aec5b23a735a13d00d14037b4ce8980561ea31ad69ba1b80dcd3e638359643cb51 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
