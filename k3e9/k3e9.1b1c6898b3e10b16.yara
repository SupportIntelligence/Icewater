
rule k3e9_1b1c6898b3e10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c6898b3e10b16"
     cluster="k3e9.1b1c6898b3e10b16"
     cluster_size="32040"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp malicious"
     md5_hashes="['000417f5bc8b994dc4423ba1a7add8da','0005ff25d2e1d9b9d3a556f075ffc6e1','001f081ba31b965872872517b207d713']"

   strings:
      $hex_string = { 312e30204d61646520696e2042656c617275732e20cff0fbe269f2e0edede520f3f169ec207ef669eae0e2fbec7e20e1e5ebe0f0f3f15fea69ec20e4e7fff3f7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
