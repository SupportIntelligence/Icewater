
rule n3e9_799eb949c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.799eb949c0000932"
     cluster="n3e9.799eb949c0000932"
     cluster_size="412"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy injector malicious"
     md5_hashes="['014b30692fab7cbec412329f9280889d','03bfdb1e09a2d0fdf139dd16f123202d','112f1b570fe4dedaf0932419abc3d6fe']"

   strings:
      $hex_string = { 85c974078b016a01ff5004c3558bec81ec040200008b018d55fc528d95fcfdffff680002000052ff500c85c07414ff75fc8d85fcfdffffff750850e837360000 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
